rule sig_20151216_60022cb980945c979ca308a945443496 {
  meta:
    description = "datamaliciousorder - file 20151216_60022cb980945c979ca308a945443496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58acca525b075337fd54cbdd5eeb1838478fb8bb6bc4f47109797be010fe6bff"

  strings:
    $s1  = "function nTQlfeLyweMAkTqOx(YBtjs){KZtXQJuiZNB= '';zEDheXwxLWv=Math.round((Math.pow(Math.sin(448), 2) + Math.pow(Math.cos(448), 2" ascii
    $s2  = ") - 1));while(true){if (zEDheXwxLWv >= (2099+157)/376){break;}rwGLALMzR[zEDheXwxLWv]=Math.round((Math.pow(Math.sin(869), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(869), 2) - 1)); while(true) { if(rwGLALMzR[zEDheXwxLWv] > YBtjs[zEDheXwxLWv].length-(654+199)/853) { break; } if" ascii
    $s4  = "w(Math.cos(470), 2) - 1)));} rwGLALMzR[zEDheXwxLWv]++;}zEDheXwxLWv++;} return KZtXQJuiZNB}" fullword ascii
    $s5  = "function nTQlfeLyweMAkTqOx(YBtjs){KZtXQJuiZNB= '';zEDheXwxLWv=Math.round((Math.pow(Math.sin(448), 2) + Math.pow(Math.cos(448), 2" ascii
    $s6  = "function XdddZaV(xrvvLxYbhBtFezcljVRqOFnpJWzJwxZNFpOs) {return !gZAcmWOwoPx(gjZefaBncIwNzKW(xrvvLxYbhBtFezcljVRqOFnpJWzJwxZNFpOs" ascii
    $s7  = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s8  = "function TwvqCDlKlPZs(flEBXRDCKheBz) {return isFinite(flEBXRDCKheBz);}" fullword ascii
    $s9  = "function pXkchfaePscplUd(PLhoeRDatWjdUGcqf,oMfyRVLPnJAVBehqCBZtcWEkVsAizzHHdN,wpJTJkoiMUtQIUHkZVwtWxvFjTavtYkwqVs){eval(PLhoeRDa" ascii
    $s10 = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s11 = "function buQnuGmyiiNUbfnasYnGIteNwISTiSeDazRZGkxygNZLsaOTkRmNGD(DYICPUVWTTfDh,sDDpuoeoAsLQra){ return IxruxQX[KLbSxkrM[AgDsN(DYI" ascii
    $s12 = "function XdddZaV(xrvvLxYbhBtFezcljVRqOFnpJWzJwxZNFpOs) {return !gZAcmWOwoPx(gjZefaBncIwNzKW(xrvvLxYbhBtFezcljVRqOFnpJWzJwxZNFpOs" ascii
    $s13 = "function gZAcmWOwoPx(WsdIEsPxlaGlbR) {return isNaN(WsdIEsPxlaGlbR);}" fullword ascii
    $s14 = "function gLydqBqlADsKBvbFb(oDMXjdWQvJ,zncZuIwfIT) {return parseInt(oDMXjdWQvJ,zncZuIwfIT);}" fullword ascii
    $s15 = "function gjZefaBncIwNzKW(yMwyRDXTnLpRBbrSImK) {return parseFloat(yMwyRDXTnLpRBbrSImK);}" fullword ascii
    $s16 = "function J(VGCtMoHTTZgjON,ZOBUppuakHKHy,PbapYoCWUhd) {VGCtMoHTTZgjON[ZOBUppuakHKHy]=PbapYoCWUhd;}" fullword ascii
    $s17 = "function AgDsN(HKtKPCHQIbA,oTUypBqCQMxTE,aSPcCmbw){CcNh=gLydqBqlADsKBvbFb(HKtKPCHQIbA,oTUypBqCQMxTE);IzIKO=CcNh.toString(aSPcCmb" ascii
    $s18 = "function pXkchfaePscplUd(PLhoeRDatWjdUGcqf,oMfyRVLPnJAVBehqCBZtcWEkVsAizzHHdN,wpJTJkoiMUtQIUHkZVwtWxvFjTavtYkwqVs){eval(PLhoeRDa" ascii
    $s19 = "function AgDsN(HKtKPCHQIbA,oTUypBqCQMxTE,aSPcCmbw){CcNh=gLydqBqlADsKBvbFb(HKtKPCHQIbA,oTUypBqCQMxTE);IzIKO=CcNh.toString(aSPcCmb" ascii
    $s20 = "w);return IzIKO;}" fullword ascii

  condition:
    uint16(0) == 0x4c4b and
    8 of them
}