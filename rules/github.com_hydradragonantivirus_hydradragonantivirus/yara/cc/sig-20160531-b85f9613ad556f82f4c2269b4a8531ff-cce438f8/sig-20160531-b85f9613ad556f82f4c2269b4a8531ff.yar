rule sig_20160531_b85f9613ad556f82f4c2269b4a8531ff {
  meta:
    description = "datamaliciousorder - file 20160531_b85f9613ad556f82f4c2269b4a8531ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a32e8d505a49858a6d015f755810beacde09c45d7621738288f4c006d9fdc235"

  strings:
    $s1  = "var gIDyN=function(){return WScript.CreateObject(iYDhYOEhkXnPfywrwjCBzAgt[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function uXQbu(PRCbxge,RRqHuyR){return PRCbxge.charAt(RRqHuyR);}" fullword ascii
    $s3  = "function EFgRjDQJjB(){return doXvfhwOZSyO(iYDhYOEhkXnPfywrwjCBzAgt[13],[0,3,6],iYDhYOEhkXnPfywrwjCBzAgt[14]);}" fullword ascii
    $s4  = "function WBnEGZcB(){return doXvfhwOZSyO(iYDhYOEhkXnPfywrwjCBzAgt[11],[2,4,8,10],iYDhYOEhkXnPfywrwjCBzAgt[12]);}" fullword ascii
    $s5  = "function aQQhWMDB(nFHCvFrfaWpLw) {var ZQbvLqaApDpgcQOxTzyhLLg = gHMQjLgGnyByZDQj.join(iYDhYOEhkXnPfywrwjCBzAgt[7]);var DHdxrQFxJ" ascii
    $s6  = "rHuhYsUTfzst, sHhutbdqNkLXhggvRjQKW);else CIOWOJgKvBoIp += KYRYADxa(DHdxrQFxJurHuhYsUTfzst, sHhutbdqNkLXhggvRjQKW, nMlqrSXwphURx" ascii
    $s7  = "function doXvfhwOZSyO(OmbVaYfzuTwX,ZHFWvXLWmMtO,QtpLQArk){QGievaTUsoQ=OmbVaYfzuTwX.split(QtpLQArk);vxgIf = iYDhYOEhkXnPfywrwjCBz" ascii
    $s8  = "soiPjNQLzlg);} while (ibrTCIdgg < nFHCvFrfaWpLw.length);return CIOWOJgKvBoIp;}" fullword ascii
    $s9  = "function aQQhWMDB(nFHCvFrfaWpLw) {var ZQbvLqaApDpgcQOxTzyhLLg = gHMQjLgGnyByZDQj.join(iYDhYOEhkXnPfywrwjCBzAgt[7]);var DHdxrQFxJ" ascii
    $s10 = " CIOWOJgKvBoIp += po(DHdxrQFxJurHuhYsUTfzst);else if (nZucVQmSVRPfJybZKPjQf == 64) CIOWOJgKvBoIp += bOMAIlUuJFgQHwpiH(DHdxrQFxJu" ascii
    $s11 = "function LbmXgJIW(){return doXvfhwOZSyO(iYDhYOEhkXnPfywrwjCBzAgt[9],[1,5,7],iYDhYOEhkXnPfywrwjCBzAgt[10]);}" fullword ascii
    $s12 = "function doXvfhwOZSyO(OmbVaYfzuTwX,ZHFWvXLWmMtO,QtpLQArk){QGievaTUsoQ=OmbVaYfzuTwX.split(QtpLQArk);vxgIf = iYDhYOEhkXnPfywrwjCBz" ascii
    $s13 = "function po(qwSjMxMvlVaZXCmmPeyznXe){return String.fromCharCode(qwSjMxMvlVaZXCmmPeyznXe);}" fullword ascii
    $s14 = "function KYRYADxa(uxpSzjecTPgA,mHczqgIzxGczqpTK,HHZFGob){return String.fromCharCode(uxpSzjecTPgA,mHczqgIzxGczqpTK,HHZFGob);}" fullword ascii
    $s15 = "var JecrMzeZ=function(){return new ActiveXObject(iYDhYOEhkXnPfywrwjCBzAgt[1]);}();" fullword ascii
    $s16 = "function xAymaitpOdAolg(){return gIDyN.ExpandEnvironmentStrings(LbmXgJIW())}" fullword ascii
    $s17 = "function bOMAIlUuJFgQHwpiH(jphOgenESBg,RUMxDYjPus){return String.fromCharCode(jphOgenESBg,RUMxDYjPus);}" fullword ascii
    $s18 = "(CaXjwzKsuWC,0x1,0x0)}function ItWaHzDksI(QxdYY,wJtSQB,rfPnoti){var iIvdgU=QxdYY.createtextfile(wJtSQB,true);iIvdgU.WriteLine(rf" ascii
    $s19 = "(CaXjwzKsuWC,0x1,0x0)}function ItWaHzDksI(QxdYY,wJtSQB,rfPnoti){var iIvdgU=QxdYY.createtextfile(wJtSQB,true);iIvdgU.WriteLine(rf" ascii
    $s20 = "function gWBWmpDvUIa(tSWnzjIkkEZiH,CaXjwzKsuWC) {var fXbVYvye=[iYDhYOEhkXnPfywrwjCBzAgt[15]];tSWnzjIkkEZiH[fXbVYvye[0]]" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}