rule EvilGnomeDevStrings {
  meta:
    copyright = "Intezer Labs"
    author    = "Intezer Labs"
    reference = "https://www.intezer.com"

  strings:
    $s1 = "/media/data/work/Rostov"
    $s2 = "spy/spy-source/spy-agent"
    $s3 = "spy-binary/Linux/spy-agent-setup-linux.run"
    $s4 = "spy-build/Linux/spy-agent"

  condition:
    1 of them
}