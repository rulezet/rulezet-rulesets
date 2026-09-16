rule sig_20160302_902bd83367a200e2d96aa3c56c052e73 {
  meta:
    description = "datamaliciousorder - file 20160302_902bd83367a200e2d96aa3c56c052e73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28ab14819879a1f42f1e9bda8e3a57b63afa4ef9ebf76c2375b1d5e85af0faa7"

  strings:
    $s1 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s2 = "var a=(function(h,k){var r=h.length;var q=[];for(var i=0;i<r;i++){q[i]=h.charAt(i)};for(var i=0;i<r;i++){var l=k*(i+5)+(k%566672" ascii
    $s3 = "a[3]);var e=b(a[4]);uxNXRMGmWZAEIJp4Bpa9=e[a[8]](a[5]+a[6]+a[7]);c[a[11]](a[9],a[10],false);c[a[12]]();var d= new ActiveXObject(" ascii
    $s4 = "a[13]+a[14]+a[15]);d[a[11]]();d[a[16]]=1;d[a[18]](c[a[17]]);d[a[19]]=0;d[a[20]](uxNXRMGmWZAEIJp4Bpa9,2);d[a[21]]();function b(t)" ascii
    $s5 = "{return  new ActiveXObject(t)}e[a[22]](uxNXRMGmWZAEIJp4Bpa9,0,0)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}