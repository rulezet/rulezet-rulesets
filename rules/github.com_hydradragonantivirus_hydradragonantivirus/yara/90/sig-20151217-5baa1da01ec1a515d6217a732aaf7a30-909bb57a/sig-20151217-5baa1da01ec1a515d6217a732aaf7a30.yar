rule sig_20151217_5baa1da01ec1a515d6217a732aaf7a30 {
  meta:
    description = "datamaliciousorder - file 20151217_5baa1da01ec1a515d6217a732aaf7a30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5bbdb416bf09160373df9fbfad03019a31c9b14c9ac7725936f17a8275155e1"

  strings:
    $s1  = ".pow(Math.cos(670), 2) - 1)); while(true) { if(qJdQsFHtz[elqxKecnVTp] > JLbtr[elqxKecnVTp].length-(-694+801)/107) { break; } if " ascii
    $s2  = "function jttBCKKwhKONvrcxl(JLbtr){JLAAyibQUnX= '';elqxKecnVTp=Math.round((Math.pow(Math.sin(38), 2) + Math.pow(Math.cos(38), 2) " ascii
    $s3  = "ow(Math.cos(608), 2) - 1)));} qJdQsFHtz[elqxKecnVTp]++;}elqxKecnVTp++;} return JLAAyibQUnX}" fullword ascii
    $s4  = "- 1));while(true){if (elqxKecnVTp >= (1655+637)/382){break;}qJdQsFHtz[elqxKecnVTp]=Math.round((Math.pow(Math.sin(670), 2) + Math" ascii
    $s5  = "function jttBCKKwhKONvrcxl(JLbtr){JLAAyibQUnX= '';elqxKecnVTp=Math.round((Math.pow(Math.sin(38), 2) + Math.pow(Math.cos(38), 2) " ascii
    $s6  = "function ScebSxY(xfVmTjOmZNNPjfxLzzSCqcsBUskojnHWApLa) {return !fBNvOnYWmli(wvQndtWjUxLdoSM(xfVmTjOmZNNPjfxLzzSCqcsBUskojnHWApLa" ascii
    $s7  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s8  = "function ScebSxY(xfVmTjOmZNNPjfxLzzSCqcsBUskojnHWApLa) {return !fBNvOnYWmli(wvQndtWjUxLdoSM(xfVmTjOmZNNPjfxLzzSCqcsBUskojnHWApLa" ascii
    $s9  = "function xGghcVwvUGtusJhAQ(uwapPSHuxg,YpugbfbiVP) {return parseInt(uwapPSHuxg,YpugbfbiVP);}" fullword ascii
    $s10 = "function fBNvOnYWmli(KuQFmoRcrURndn) {return isNaN(KuQFmoRcrURndn);}" fullword ascii
    $s11 = "function zoHAkTcPdeiebFS(RmuGensyqGSDmqMqI,lldHSFnWjLRchyaMHQfQpVRvBBhZFhRoUe,dkCqZMjbRDUDUxYvyWGeSbzRbwIZiDdWUzg){eval(RmuGensy" ascii
    $s12 = "function OdxBOhihfytAHxWQJObVPkarUtRbpUqPqYDzHJgPCuCEosGEQdHsML(GTFPEOwFVEBQg,WJcjboxljVAEPy){ return WMqvMsy[LinbpIPd[NZOuL(GTF" ascii
    $s13 = "function OdxBOhihfytAHxWQJObVPkarUtRbpUqPqYDzHJgPCuCEosGEQdHsML(GTFPEOwFVEBQg,WJcjboxljVAEPy){ return WMqvMsy[LinbpIPd[NZOuL(GTF" ascii
    $s14 = "function NZOuL(aHLZnzfHuIy,NALCbEGOZKndx,zqkczSeg){zUSO=xGghcVwvUGtusJhAQ(aHLZnzfHuIy,NALCbEGOZKndx);RocwQ=zUSO.toString(zqkczSe" ascii
    $s15 = "function X(QhXjpGMSnhUp,oqnJtIOxSvcIvP){QhXjpGMSnhUp.push(oqnJtIOxSvcIvP);}" fullword ascii
    $s16 = "g);return RocwQ;}" fullword ascii
    $s17 = "function wvQndtWjUxLdoSM(NcKVFGzVjIbUsGRSpeZ) {return parseFloat(NcKVFGzVjIbUsGRSpeZ);}" fullword ascii
    $s18 = "function NZOuL(aHLZnzfHuIy,NALCbEGOZKndx,zqkczSeg){zUSO=xGghcVwvUGtusJhAQ(aHLZnzfHuIy,NALCbEGOZKndx);RocwQ=zUSO.toString(zqkczSe" ascii
    $s19 = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s20 = "function JGdBzFgOxbot(nUxAEssCsSVwB) {return isFinite(nUxAEssCsSVwB);}" fullword ascii

  condition:
    uint16(0) == 0x694c and
    8 of them
}