rule sig_20160517_cc59ca434c1b082e3ffa48cd7b509862 {
  meta:
    description = "datamaliciousorder - file 20160517_cc59ca434c1b082e3ffa48cd7b509862.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae1466bf3be69be3984eaa90a76d9accae416aff39efabb1b4d8d391e16e19ce"

  strings:
    $s1 = "var dhab4='vlvwndavfm1arxqqek e4vaequetwhahoy2vazeqbvziobloiugezoyaxro2fstgtqcenfpoztywwa2jvsyg=idqpd\\'fja22to2vmucaeivynb1xxxi" ascii
    $s2 = "+\"xp\");   swqryfvz=r4+\"v\"+\"al\";   WScript.lister=5;   swqryfvz=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}