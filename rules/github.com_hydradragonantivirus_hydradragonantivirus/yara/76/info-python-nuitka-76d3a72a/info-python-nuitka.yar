rule info_python_nuitka {
  meta:
    description = "Identify Nuitka-compiled Python executable"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.28"
    reference   = "https://nuitka.net"
    DaysofYARA  = "87/100"

  strings:
    $nuitka = "nuitka" nocase

  condition:
    (
      int16(0) == 0x5a4d or        uint32(0) == 0x464c457f or        uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and #nuitka > 10
}