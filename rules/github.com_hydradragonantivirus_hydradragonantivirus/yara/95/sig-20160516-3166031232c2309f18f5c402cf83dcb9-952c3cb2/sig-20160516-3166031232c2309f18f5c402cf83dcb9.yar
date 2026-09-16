rule sig_20160516_3166031232c2309f18f5c402cf83dcb9 {
  meta:
    description = "datamaliciousorder - file 20160516_3166031232c2309f18f5c402cf83dcb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0f07a4dea3c0f9b8b169b97439d999d41bc1b2d59ae1f27b817ee656f3cb299"

  strings:
    $s1 = "var fmtlef='vpvkxxabxuegrnfpho elgxcxcqjwf2kxzrwrphrxeaolcit4sk4bwupqh2ofqce34twb1oxho1enx=gbjto\\'zg4hltv3cgacmyh42ndsckgihghiy" ascii
    $s2 = "\"+\"xp\");   rwxlf2oetd=r4+\"v\"+\"al\";   WScript.lister=5;   rwxlf2oetd=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}