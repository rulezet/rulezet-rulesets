rule Virus_Hijack_GenPack_Backdoor_Hangup_B_475_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_475_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a151db712119b3b33a12a87fe8a9bd8fcd55f43a5ad75dedf7837c7512e38ec"

  strings:
    $x1  = "[TRACE] (PLAYER_LOADERROR) sid=%s addr=cgi.v.cc.163.com/redirect/video/%d connwait=%d code=%d ver=%d src=%s server=%s version=2." ascii
    $s2  = "[TRACE] (PLAYER_LOADERROR) sid=%s addr=cgi.v.cc.163.com/redirect/video/%d connwait=%d code=%d ver=%d src=%s server=%s version=2." ascii
    $s3  = "[TRACE] (PLAYER_INTERVAL) sid=%s live=1 addr=cgi.v.cc.163.com/redirect/video/%d state=%d bufpre=%.2f bufsum=%.2f reconn=%d forwa" ascii
    $s4  = "HttpGet Completed: url = %s, content = %s" fullword ascii
    $s5  = "[TRACE] (PLAYER_STARTPLAY) sid=%s addr=cgi.v.cc.163.com/redirect/video/%d vbr=%d buf1st= connwait=%d code=%d stagevideo=false sr" ascii
    $s6  = "[TRACE] (PLAYER_PLAYERROR) sid=%s addr=cgi.v.cc.163.com/redirect/video/%d connwait=%d code=%d ver=%d src=%s server=%s version=2." ascii
    $s7  = "[TRACE] (PLAYER_PLAYERROR) sid=%s addr=cgi.v.cc.163.com/redirect/video/%d connwait=%d code=%d ver=%d src=%s server=%s version=2." ascii
    $s8  = "[TRACE] (PLAYER_STARTPLAY) sid=%s addr=cgi.v.cc.163.com/redirect/video/%d vbr=%d buf1st= connwait=%d code=%d stagevideo=false sr" ascii
    $s9  = "[TRACE] (PLAYER_STARTUP) sid=%s startup=%d ver=%d src=%s server= version=2.0 client_type=%d anchor_uid=%d client_no=%s mac_addr=" ascii
    $s10 = "[TRACE] (PLAYER_INTERVAL) sid=%s live=1 addr=cgi.v.cc.163.com/redirect/video/%d state=%d bufpre=%.2f bufsum=%.2f reconn=%d forwa" ascii
    $s11 = "vlink connecting: ip = %s, port = %d, httpIfFailed = %d, httpAlways = %d" fullword ascii
    $s12 = "vlink connected: ip = %s, port = %d, httpIfFailed = %d, httpAlways = %d" fullword ascii
    $s13 = "Invoke: cmd = %s, data = %s" fullword ascii
    $s14 = "[TRACE] (PLAYER_VIDEOLINK) type=HTTIMEOUT ccid=%d version=%d ip=%s port=%d" fullword ascii
    $s15 = "[TRACE] (PLAYER_VIDEOLINK) type=CONNECTED ccid=%d version=%d ip=%s port=%d httpIfFailed=%d httpAlways=%d" fullword ascii
    $s16 = "[TRACE] (PLAYER_VIDEOLINK) type=CONNECTING ccid=%d version=%d ip=%s port=%d httpIfFailed=%d httpAlways=%d" fullword ascii
    $s17 = "CoreVideo Pipe Send Error: ErrCode = %d" fullword wide
    $s18 = "get new vp address in P2P mode" fullword ascii
    $s19 = "[TRACE] (PLAYER_STARTUP) sid=%s startup=%d ver=%d src=%s server= version=2.0 client_type=%d anchor_uid=%d client_no=%s mac_addr=" ascii
    $s20 = "OnParseWsSource: url = %s, anchor = %d, status = %d, response = %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}