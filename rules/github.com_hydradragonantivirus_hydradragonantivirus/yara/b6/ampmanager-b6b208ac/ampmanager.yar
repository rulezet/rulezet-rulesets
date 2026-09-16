rule AmpManager {
  meta:
    copyright = "Intezer Labs"
    author    = "Intezer Labs"
    reference = "https://www.intezer.com"

  strings:
    $a0 = { C7 85 ?? F8 FF FF ?? 00 00 11 C7 85 ?? F8 FF FF 00 00 00 00 C7 85 ?? F8 FF FF ?? 00 00 00 }
    $b0 = "ampserver/main.cpp"
    $b1 = "M-SEARCH * HTTP/1.1"
    $b2 = "rm -f /usr/bin/ammint | killall ammint 2>/dev/null &"
    $b3 = "ln -s /etc/init.d/%s %s"
    $b4 = "camplz123"

  condition:
    all of them
}