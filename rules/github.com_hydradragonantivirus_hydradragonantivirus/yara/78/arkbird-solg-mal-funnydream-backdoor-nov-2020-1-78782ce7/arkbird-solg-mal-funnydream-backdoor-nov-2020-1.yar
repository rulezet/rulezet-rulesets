rule ARKBIRD_SOLG_Mal_Funnydream_Backdoor_Nov_2020_1: FILE {
  meta:
    description = "Detect backdoor used by FunnyDream (November 2020)"
    author      = "Arkbird_SOLG"
    id          = "48120ba2-adaa-5098-8d8c-5c32bbafb9f6"
    date        = "2020-12-19"
    modified    = "2020-12-19"
    reference   = "https://insight-jp.nttsecurity.com/post/102glv5/pandas-new-arsenal-part-3-smanager"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-19/Mal_FunnyDream_Backdoor_Nov_2020_1.yar#L1-L22"
    license_url = "N/A"
    logic_hash  = "d12c465c735f09295b382fd5679d411c5114c232dabc22be84151e436f8fa199"
    score       = 75
    quality     = 67
    tags        = "FILE"
    hash1       = "ce5c8741bffa8de5093d1831d736a7e478a54baa3676da37cde24f38d10f3529"

  strings:
    $s1  = "%d%d%d %d:%d"
    $s2  = { 73 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 00 00 50 72 6f 78 79 45 6e 61 62 6c 65 00 50 72 6f 78 79 53 65 72 76 65 }
    $s3  = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
    $s4  = "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nSet-Cookie: %u%s%s\r\nServer: Simple\r\nCache-Control: no-store\r\nPragma: no-cache"
    $s5  = "CONNECT %s:%d HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1;)\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 0\r\nHost: %s\r\nPragma: no-cache\r\n\r\n"
    $s6  = { 31 32 33 34 35 36 00 00 55 73 65 72 2d 30 30 31 }
    $s7  = "%s %s%s/%s/%08X%08X/%u/%u/%u/%u/%u/%u/%08X%08x"
    $s8  = { 63 6c 74 2e 65 78 65 00 44 6c 6c 49 6e 73 74 61 6c 6c 00 53 74 61 72 74 }
    $s9  = "200 Connection established"
    $s10 = { 5c 63 6d 64 c7 85 e0 fe ff ff 2e 65 78 65 }

  condition:
    uint16(0) == 0x5a4d and filesize > 90KB and 6 of them
}