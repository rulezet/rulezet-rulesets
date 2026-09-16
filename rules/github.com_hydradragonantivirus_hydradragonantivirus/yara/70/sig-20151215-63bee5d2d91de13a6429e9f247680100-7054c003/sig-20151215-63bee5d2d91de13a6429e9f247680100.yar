rule sig_20151215_63bee5d2d91de13a6429e9f247680100 {
  meta:
    description = "datamaliciousorder - file 20151215_63bee5d2d91de13a6429e9f247680100.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8582f45b268a76ceb6d57540d1802a6ae9854ad1d1e46115b64d3b49778eb363"

  strings:
    $s1  = "(Math.cos(952), 2) - 1)));} tFIshKIEf[kbQFwYEXQot]++;}} return zznwMiAmYhr}" fullword ascii
    $s2  = "h.pow(Math.cos(18), 2) - 1)); while(true) { if(tFIshKIEf[kbQFwYEXQot] > ypFmr[kbQFwYEXQot].length-(47+344)/391) { break; } if (G" ascii
    $s3  = "function QODXkQQexvaNrqkHY(ypFmr){zznwMiAmYhr= P[1759];for(kbQFwYEXQot=Math.round((Math.pow(Math.sin(26), 2) + Math.pow(Math.cos" ascii
    $s4  = "function QODXkQQexvaNrqkHY(ypFmr){zznwMiAmYhr= P[1759];for(kbQFwYEXQot=Math.round((Math.pow(Math.sin(26), 2) + Math.pow(Math.cos" ascii
    $s5  = "function v(aXzYgrMDhfun,oOqCxsmfHmrgAN){aXzYgrMDhfun.push(oOqCxsmfHmrgAN);}function v2(vseTXVsuQJbwzNfZ){if(GxUwYVb(vseTXVsuQJbw" ascii
    $s6  = "zNfZ)) {return (String.fromCharCode(vseTXVsuQJbwzNfZ) + String.fromCharCode((32217+420)/759));}}" fullword ascii
    $s7  = "function GxUwYVb(KYfVXwpJOQyAZzHXopYFVrweyJjPWbPkosps) {return !isNaN(parseFloat(KYfVXwpJOQyAZzHXopYFVrweyJjPWbPkosps)) && isFin" ascii
    $s8  = "function GxUwYVb(KYfVXwpJOQyAZzHXopYFVrweyJjPWbPkosps) {return !isNaN(parseFloat(KYfVXwpJOQyAZzHXopYFVrweyJjPWbPkosps)) && isFin" ascii
    $s9  = "var P=new Array();" fullword ascii
    $s10 = "function XBhaQfGrKqhNfVD(RBxsRRnjASgTCRyQY){eval(RBxsRRnjASgTCRyQY)}" fullword ascii
    $s11 = "function iHKqmrxiEhnYVzOfzLvpGmuQJinViTCKZMRWQEFDZUoGtlVjCJeozE(clJkZZKjCIWNR,UaqBoleZiusKKW){ return tPgBNno[UMdFHDHt[lQoQS(clJ" ascii
    $s12 = "function lQoQS(zoxSsDyxdkp,SbpjmzahUgyMn,uxOtYKJo){zRxE=parseInt(zoxSsDyxdkp,SbpjmzahUgyMn);VVRuZ=zRxE.toString(uxOtYKJo);return" ascii
    $s13 = "function iHKqmrxiEhnYVzOfzLvpGmuQJinViTCKZMRWQEFDZUoGtlVjCJeozE(clJkZZKjCIWNR,UaqBoleZiusKKW){ return tPgBNno[UMdFHDHt[lQoQS(clJ" ascii
    $s14 = "function dhbSbXgEIpf(KAtIuhBj,rKrbAR){return KAtIuhBj.split(rKrbAR)}" fullword ascii
    $s15 = "function v(aXzYgrMDhfun,oOqCxsmfHmrgAN){aXzYgrMDhfun.push(oOqCxsmfHmrgAN);}function v2(vseTXVsuQJbwzNfZ){if(GxUwYVb(vseTXVsuQJbw" ascii
    $s16 = "function lQoQS(zoxSsDyxdkp,SbpjmzahUgyMn,uxOtYKJo){zRxE=parseInt(zoxSsDyxdkp,SbpjmzahUgyMn);VVRuZ=zRxE.toString(uxOtYKJo);return" ascii
    $s17 = " VVRuZ;}function XBhaQfGrKqhNfVD(RBxsRRnjASgTCRyQY,bSocTzklApbTWfdcKygHsrUWLIUGmcIcAu,UYQSiIXlUZkxZrEMpvsOFCKgzQwrXNIUHQe){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}