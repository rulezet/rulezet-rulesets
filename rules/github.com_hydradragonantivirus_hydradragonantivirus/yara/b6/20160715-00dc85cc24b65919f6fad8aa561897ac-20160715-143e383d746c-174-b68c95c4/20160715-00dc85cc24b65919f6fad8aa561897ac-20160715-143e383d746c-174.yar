rule _20160715_00dc85cc24b65919f6fad8aa561897ac_20160715_143e383d746c_174 {
  meta:
    description = "datamaliciousorder - from files 20160715_00dc85cc24b65919f6fad8aa561897ac.js, 20160715_143e383d746c12fc979e5a241e7a7081.js, 20160715_14bb52b4f4e160a8bb118eea23b1857f.js, 20160715_1dab40a03f92aa84485c8f3670578a5b.js, 20160715_342d90c420333ef07f325f926ba651d8.js, 20160715_3c9848e3fb7f4f2ea4812897aeded8cb.js, 20160715_4045f0ced26c1f691e5a638d4a1341d5.js, 20160715_4a3f75230fd5291b1c63a29bfb7ad456.js, 20160715_4dd0fe0672a43849b041b0c143efdef0.js, 20160715_5d51601a1653249b1b3d633c2922ed43.js, 20160715_7cad488cd0f0e1a289792017654a237d.js, 20160715_8a4c27514cac36cf615690d7009b69fb.js, 20160715_ace5038dfb17f9811fa330bb535a2923.js, 20160715_b9c37356c74089711aa0fdee6e136191.js, 20160715_bad1b57566ad0b4c9e8a5bed55d91aea.js, 20160715_c396fc5b05e70dac360dea8134152bfb.js, 20160715_eb71840eb58189d4493fdb0662cfa069.js, 20160715_f1f6ee5a0df4e91c32c499f7c54712c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0df23f2a69855cf25ab93c029787b822035d5efab414b0199ee164be3e386e80"
    hash2       = "97cc036ce93b279d4a4eff5ae3148c7d716dc38b894565bb8c0929020d9c18bd"
    hash3       = "8029eae866173f789ac8c535f3f1303dfaf7dc9c445da5d9d1962e926ea02449"
    hash4       = "b46000decac9dffd8c5c6b760213afb2ed8414c1017ff1bf2e8bf3691dd147ec"
    hash5       = "452e4b0f35c138fc07c1d796ceaaca756451a1cb72a93c05015a4e3c656424d7"
    hash6       = "3e4efd2bfdda55102b9f3226c37e0965f83537b2b5f7e4db6aeed41dcf660386"
    hash7       = "cdcccb70e4ef61f4ac8369170d0f12ab85996f1361fa5fbe73e321e2a78a40be"
    hash8       = "442276488c6244a310131328c53c44c684499fb948b4731b60c85f14a0072a3e"
    hash9       = "ab9a0d67101e0ba8b452e079ef79d96006f1bd22f39b1db2d9160b90db5bcd15"
    hash10      = "c89a0d2c7a0b620ae238a7de7d9ce3b878d052159f9b7e81f5907d3925c65c1b"
    hash11      = "7ff2056de3a02f0174f8da8f5746897546fcff14e8663f1de0cfa6b920f1d48f"
    hash12      = "93764514efee1b7528f6d5212e2570fd61f15316f5562d6377f58dc32128c344"
    hash13      = "083a86a731119a6c2806097cb9b0eb9708335fb1c365e2f1a9e6791957d64d9b"
    hash14      = "5d7620acd15357b1d945316a6c7b1bbb2652d804fc8a178f0d6677baf35cffbf"
    hash15      = "b7c35306e7726730b60131dc38f04f4064d8fcaee58b04536b11c519f5c96a3f"
    hash16      = "f63672b665a71b16e756b1e5a88c57ce759b07b039f7deb425d9a36d31736e67"
    hash17      = "d59db6b21bf63554e1a4280bf1b20f7159b446168e2f0fc1c57de18878426b4e"
    hash18      = "a42ea3b158fa77a8d1963b9bfe28709f6047bf5c30ece129dedc35cbda78b575"

  strings:
    $s1  = "var votNovijPovorotjDevoBareNnna_PRigund = new Array(-1, -1, -1, -1, -1, -1,-1,-1);" fullword ascii
    $s2  = "String.prototype.votNovijPovorotjDevoBareNnna_center2 = function () {" fullword ascii
    $s3  = "if ((!votNovijPovorotjDevoBareNnna_check || !object[votNovijPovorotjDevoBareNnna_property]) && typeof object.prototype[votNovijP" ascii
    $s4  = "if ((!votNovijPovorotjDevoBareNnna_check || !object[votNovijPovorotjDevoBareNnna_property]) && typeof object.prototype[votNovijP" ascii
    $s5  = "String.prototype.votNovijPovorotjDevoBareNnna_center4 = function() {" fullword ascii
    $s6  = "    return new votNovijPovorotjDevoBareNnna_weirshtrasse(votNovijPovorotjDevoBareNnna_param1.x - votNovijPovorotjDevoBareNnna_pa" ascii
    $s7  = "    return new votNovijPovorotjDevoBareNnna_weirshtrasse(votNovijPovorotjDevoBareNnna_param1.x - votNovijPovorotjDevoBareNnna_pa" ascii
    $s8  = "} catch (votNovijPovorotjDevoBareNnna_RFXuYwO) {WScript.echo(votNovijPovorotjDevoBareNnna_RFXuYwO.message);" fullword ascii
    $s9  = "        } while (votNovijPovorotjDevoBareNnna_i < votNovijPovorotjDevoBareNnna_len && votNovijPovorotjDevoBareNnna_c4 == -1);" fullword ascii
    $s10 = "        } while (votNovijPovorotjDevoBareNnna_i < votNovijPovorotjDevoBareNnna_len && votNovijPovorotjDevoBareNnna_c3 == -1);" fullword ascii
    $s11 = "        } while (votNovijPovorotjDevoBareNnna_i < votNovijPovorotjDevoBareNnna_len && votNovijPovorotjDevoBareNnna_c1 == -1);" fullword ascii
    $s12 = "function votNovijPovorotjDevoBareNnna_achievment(votNovijPovorotjDevoBareNnna_bidttt){if(votNovijPovorotjDevoBareNnna_bidttt==1)" ascii
    $s13 = "function votNovijPovorotjDevoBareNnna_achievment(votNovijPovorotjDevoBareNnna_bidttt){if(votNovijPovorotjDevoBareNnna_bidttt==1)" ascii
    $s14 = "ovorotjDevoBareNnna_property] == 'function') object[votNovijPovorotjDevoBareNnna_property] = function(){" fullword ascii
    $s15 = "jPovorotjDevoBareNnna_chosen, true);" fullword ascii
    $s16 = "votNovijPovorotjDevoBareNnna_weirshtrasse.votNovijPovorotjDevoBareNnna_subtract = function(votNovijPovorotjDevoBareNnna_param1, " ascii
    $s17 = "votNovijPovorotjDevoBareNnna_weirshtrasse.votNovijPovorotjDevoBareNnna_sameOrN = function(votNovijPovorotjDevoBareNnna_param1, v" ascii
    $s18 = "votNovijPovorotjDevoBareNnna_libel = votNovijPovorotjDevoBareNnna_libel.concat(new Array(-1, -1, -1, -1, -1));" fullword ascii
    $s19 = "votNovijPovorotjDevoBareNnna_weirshtrasse.angle = function(votNovijPovorotjDevoBareNnna_p) {" fullword ascii
    $s20 = "votNovijPovorotjDevoBareNnna_weirshtrasse.create = function(){" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}