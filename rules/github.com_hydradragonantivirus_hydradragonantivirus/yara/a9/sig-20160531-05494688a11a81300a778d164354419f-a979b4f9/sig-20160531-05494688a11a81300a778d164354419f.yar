rule sig_20160531_05494688a11a81300a778d164354419f {
  meta:
    description = "datamaliciousorder - file 20160531_05494688a11a81300a778d164354419f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23fa1c1f7ce4aca2dbd0f06d7a0ab4412ecc9d68bb5bad2c17b2645a02b138c7"

  strings:
    $s1  = "var kyDfqMdiPlRLq=function(){return WScript.CreateObject(lvKXAZAHxc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function MZMVZMIiZdaRKEgBWhRKdCzk(kFpTQRqztYildQBArMbuaQzJ,iyGGOOuVVjFsVDJTI){return kFpTQRqztYildQBArMbuaQzJ.indexOf(iyGGOOuVVj" ascii
    $s3  = "function iRIobiUaCF(tWBLMjCxbYXGn) {var ohsxvWeAEXXUjaKmH = xXsFqcnWauUOWbURzMAjueMp.join(lvKXAZAHxc[7]);var VFmPpbxdQwXke, pRXr" ascii
    $s4  = "function quJTNagiJMT(PZsXXJ,BGqlQh){return PZsXXJ.charAt(BGqlQh);}" fullword ascii
    $s5  = "function MZMVZMIiZdaRKEgBWhRKdCzk(kFpTQRqztYildQBArMbuaQzJ,iyGGOOuVVjFsVDJTI){return kFpTQRqztYildQBArMbuaQzJ.indexOf(iyGGOOuVVj" ascii
    $s6  = "function NmGbd(){return blBOQ(lvKXAZAHxc[13],[0,3,6],lvKXAZAHxc[14]);}" fullword ascii
    $s7  = "DAmSSATJQN += txaQYLbHwbBW(VFmPpbxdQwXke, pRXrzOYvxGgsIdnnXic, VbzZmIjQLylvoDErG);} while (irtyfbEqKUSUdfE < tWBLMjCxbYXGn.lengt" ascii
    $s8  = "function reIIqYgxFOTTmF(){return blBOQ(lvKXAZAHxc[11],[2,4,8,10],lvKXAZAHxc[12]);}" fullword ascii
    $s9  = "function xY(BUzGPAdvhFYAmNdaO){return String.fromCharCode(BUzGPAdvhFYAmNdaO);}" fullword ascii
    $s10 = "push(\"v\");xXsFqcnWauUOWbURzMAjueMp.push(\"w\");xXsFqcnWauUOWbURzMAjueMp.push(\"x\");xXsFqcnWauUOWbURzMAjueMp.push(\"y\");xXsFq" ascii
    $s11 = "function txaQYLbHwbBW(HhRVY,VKJTXvBYqxIuxrSQSbMwK,QFFzVwEUEEtZo){return String.fromCharCode(HhRVY,VKJTXvBYqxIuxrSQSbMwK,QFFzVwEU" ascii
    $s12 = "function dcyRfOxrP(){return blBOQ(lvKXAZAHxc[9],[1,5,7],lvKXAZAHxc[10]);}" fullword ascii
    $s13 = "function blBOQ(hVHvVyY,dlrtbKWeBMRj,whCukkX){jhhfeSYX=hVHvVyY.split(whCukkX);jZBsS = lvKXAZAHxc[0];for(qSUYYhYbTWR=0;qSUYYhYbTWR" ascii
    $s14 = "function tOHuGmfyQqqV(blTSznwRTv,CBnkLpIs) {var CBQcObyN=[lvKXAZAHxc[15]];blTSznwRTv[CBQcObyN[0]]" fullword ascii
    $s15 = "<dlrtbKWeBMRj.length;qSUYYhYbTWR++) {jZBsS+=jhhfeSYX[dlrtbKWeBMRj[qSUYYhYbTWR]];}return jZBsS.substring(3,jZBsS.length);}" fullword ascii
    $s16 = "var ewqkzzJe=function(){return new ActiveXObject(lvKXAZAHxc[1]);}();" fullword ascii
    $s17 = "function txaQYLbHwbBW(HhRVY,VKJTXvBYqxIuxrSQSbMwK,QFFzVwEUEEtZo){return String.fromCharCode(HhRVY,VKJTXvBYqxIuxrSQSbMwK,QFFzVwEU" ascii
    $s18 = "function yiFHepPB(){return kyDfqMdiPlRLq.ExpandEnvironmentStrings(dcyRfOxrP())}" fullword ascii
    $s19 = "mPpbxdQwXke);else if (GhvemPUAhPUe == 64) zWGzmjDAmSSATJQN += BuAxqVzXbkCsIECqbz(VFmPpbxdQwXke, pRXrzOYvxGgsIdnnXic);else zWGzmj" ascii
    $s20 = "function blBOQ(hVHvVyY,dlrtbKWeBMRj,whCukkX){jhhfeSYX=hVHvVyY.split(whCukkX);jZBsS = lvKXAZAHxc[0];for(qSUYYhYbTWR=0;qSUYYhYbTWR" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}