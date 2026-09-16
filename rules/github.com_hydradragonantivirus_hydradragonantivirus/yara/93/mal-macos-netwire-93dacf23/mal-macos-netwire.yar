rule mal_macos_netwire {
  meta:
    description = "Identify the macOS Netwire Client"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.10"
    sample      = "07a4e04ee8b4c8dc0f7507f56dc24db00537d4637afee43dbb9357d4d54f6ff4"
    DaysofYARA  = "69/100"

  strings:
    $s0 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
    $s1 = "%PATH%"
    $s2 = "%HOME%"
    $s3 = "%USER%"

    $c0 = {
      e8 [4]                83 c4 0c              bf ff 00 00 00        ba f8 e? ?? ??        89 d9                 57                    68 ?? ?? ?? ??        57                    e8 [4]                83 c4 0c              ba f8 e? ?? ??        89 d9                 57                    68 ?? ?? ?? ??        57                    e8 [4]                83 c4 0c              bf 20 00 00 00        ba f8 e? ?? ??        89 d9                 57                    68 ?? ?? ?? ??        57                    e8 [4]                83 c4 0c              ba 2a e? ?? ??        89 d9                 56                    68 ?? ?? ?? ??        56                    e8 [3] ??           }

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    2 of them
}