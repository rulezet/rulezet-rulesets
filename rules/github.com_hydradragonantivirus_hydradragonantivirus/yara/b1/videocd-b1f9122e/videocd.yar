rule videocd: VCD {
  meta:
    author = "Jaume Martin"

  strings:
    $a = { 45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58 }

  condition:
    $a at 0
}