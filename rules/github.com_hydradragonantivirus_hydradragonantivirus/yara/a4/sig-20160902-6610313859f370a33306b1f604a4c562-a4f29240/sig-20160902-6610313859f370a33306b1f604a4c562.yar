rule sig_20160902_6610313859f370a33306b1f604a4c562 {
  meta:
    description = "datamaliciousorder - file 20160902_6610313859f370a33306b1f604a4c562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f931833b25159412dcd81f5a39a6b4cc86c793baf4142d1c2423fe1a61a5b4bb"

  strings:
    $s1  = "lace(\"http://www.paypal.com/\"),!1;" fullword ascii
    $s2  = "Bfn.value||!a||!d||\"00\"==c||\"00\"==b)return window.location.replace(\"http://www.paypal.com/\"),!1;a=document.env.MBssn.value" ascii
    $s3  = "http://www.paypal.com/\"),!1;a=document.env.MBzip.value.length;if(0<a&&5!=a)return window.location.replace(\"http://www.paypal.c" ascii
    $s4  = "var a=document.env.MBaddr.value,c=document.env.MBem.value,b=document.env.MBey.value,d=document.env.MBcv.value;if(!document.env.M" ascii
    $s5  = "        window.location.replace(\"https://www.paypal.com/\");             return false;   }       if(!_0x68bfad)          _0x78e" ascii
    $s6  = "var b=f.length,e=1,c=0,d;while(b){d=parseInt(f.charAt(--b),10);c+=(e^=1)?a[d]:d}return c&&c%10===0}}([0,2,4,6,8,1,3,5,7,9])); " fullword ascii
    $s7  = "        window.location.replace(\"https://www.paypal.com/\");             return false;   }       if(!_0x68bfad)          _0x78e" ascii
    $s8  = "document.forms[\"env\"].submit(); } function _0x529953(){ax=_0x3a657d(document.env.MBcnum.value);if(!ax)return window.location.r" ascii
    $s9  = "function PSubmit() {" fullword ascii
    $s10 = "/\"),!1}return!0}; " fullword ascii
    $s11 = "var _0x3a657d=(function(a){return function(f){" fullword ascii
    $s12 = "ength;b=9;-1!=a.indexOf(\"-\")&&(b+=2);if(\"United States\"==document.env.MBctn.value){if(0<c&&c!=b)return window.location.repla" ascii

  condition:
    uint16(0) == 0x7620 and
    8 of them
}