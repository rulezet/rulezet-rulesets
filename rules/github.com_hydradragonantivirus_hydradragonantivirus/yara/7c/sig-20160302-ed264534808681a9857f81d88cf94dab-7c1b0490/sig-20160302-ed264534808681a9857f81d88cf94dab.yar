rule sig_20160302_ed264534808681a9857f81d88cf94dab {
  meta:
    description = "datamaliciousorder - file 20160302_ed264534808681a9857f81d88cf94dab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73865ce86a4521b06e639a1e67eb054c1fff78806d1a5aa11cdc99033a3e8015"

  strings:
    $s1 = "var a=(function(q,m){var f=q.length;var s=[];for(var j=0;j<f;j++){s[j]=q.charAt(j)};for(var j=0;j<f;j++){var h=m*(j+5)+(m%438711" ascii
    $s2 = "var a=(function(q,m){var f=q.length;var s=[];for(var j=0;j<f;j++){s[j]=q.charAt(j)};for(var j=0;j<f;j++){var h=m*(j+5)+(m%438711" ascii
    $s3 = "]();function b(t){return  new ActiveXObject(t)}e[a[22]](RcfgdIH147jUuKSpQE5XQmSeYS,0,0)" fullword ascii
    $s4 = "a[2]+a[3]);var e=b(a[4]);RcfgdIH147jUuKSpQE5XQmSeYS=e[a[8]](a[5]+a[6]+a[7]);c[a[11]](a[9],a[10],false);c[a[12]]();var d= new Act" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}