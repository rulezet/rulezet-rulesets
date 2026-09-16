rule sig_20160517_0d0cc7e21519d3dd856475d534e88c00 {
  meta:
    description = "datamaliciousorder - file 20160517_0d0cc7e21519d3dd856475d534e88c00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "156e9bb4fbc235c94e06009cb63d1ed49164ad3b96ade099bfc2f64fddbdf9e9"

  strings:
    $s1 = "var d2de4='vfwfzlaooxrnridgjt wqezsldsnrp3cd1jobbplhpdvodzgojmnbzjklqpkgxld1chcajxoix1enihkp2bo=d1azb\\'egquztscljdczghbensdfevi" ascii
    $s2 = "+\"v\"+\"al\";   WScript.lister=5;   tvbjlyrpga=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {  " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}