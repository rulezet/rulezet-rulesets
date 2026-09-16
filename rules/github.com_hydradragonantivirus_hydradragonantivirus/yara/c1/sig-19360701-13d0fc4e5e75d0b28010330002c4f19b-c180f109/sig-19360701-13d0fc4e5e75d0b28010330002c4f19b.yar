rule sig_19360701_13d0fc4e5e75d0b28010330002c4f19b {
  meta:
    description = "datamaliciousorder - file 19360701_13d0fc4e5e75d0b28010330002c4f19b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8d8bb46863133ae5d877dcd1ba32c61910119ac86c6f5d7dbeb8c57a864d3a5"

  strings:
    $s1 = "pre_control1=undefined;pre_with4=undefined;pre_malicious7=undefined;pre_purposes=undefined;pre_software=undefined;pre_following=" ascii
    $s2 = " pre_informationInformation4[{oo0:'\\u0053'}.oo0+{uth1:'\\u006c'}.uth1+{e3:'\\u0065'}.e3+{bo0:'\\u0065'}.bo0+{i1:'\\u0070'}.i1](" ascii
    $s3 = "3+{ont1:'\\u0072'}.ont1]((Math[{tor1:'\\u0072'}.tor1+{ay0:'\\u0061'}.ay0+{t0:'\\u006e'}.t0+{ck3:'\\u0064'}.ck3+{er3:'\\u006f'}.e" ascii
    $s4 = "{n1:'\\u006f'}.n1+{ers3:'\\u006f'}.ers3+{ont1:'\\u0072'}.ont1]((Math[{tor1:'\\u0072'}.tor1+{ay0:'\\u0061'}.ay0+{t0:'\\u006e'}.t0" ascii
    $s5 = "undefined;pre_following=undefined;pre_with4=undefined;pre_andor0=undefined;pre_includes=undefined;pre_this=undefined;pre_their=u" ascii
    $s6 = "    pre_PayPal[{o3:'\\u006f'}.o3+{n2:'\\u0070'}.n2+{o0:'\\u0065'}.o0+{is1:'\\u006e'}.is1]({n0:'\\u0047'}.n0+{nfo3:'\\u0045'}.nfo" ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}