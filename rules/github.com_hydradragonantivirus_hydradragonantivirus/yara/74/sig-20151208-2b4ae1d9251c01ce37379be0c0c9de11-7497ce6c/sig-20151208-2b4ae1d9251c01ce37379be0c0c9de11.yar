rule sig_20151208_2b4ae1d9251c01ce37379be0c0c9de11 {
  meta:
    description = "datamaliciousorder - file 20151208_2b4ae1d9251c01ce37379be0c0c9de11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0bf45ef93d275e544dae533e4c9be58cfbc439bc24ec46f6ec49b064263da61"

  strings:
    $s1  = "function cEZchQDLlupXGFNni(uRckI){cbQFglASKDy= '';for(aRzLoqbecRr=(-420+420)/298; aRzLoqbecRr < (1624+136)/880; aRzLoqbecRr++) {" ascii
    $s2  = "function cEZchQDLlupXGFNni(uRckI){cbQFglASKDy= '';for(aRzLoqbecRr=(-420+420)/298; aRzLoqbecRr < (1624+136)/880; aRzLoqbecRr++) {" ascii
    $s3  = "function bnkQjrl(ZZXYZkgLBnZIJrKZBWZeuGVdqyMzyfPJmlLT) {return !isNaN(parseFloat(ZZXYZkgLBnZIJrKZBWZeuGVdqyMzyfPJmlLT)) && isFin" ascii
    $s4  = "function bnkQjrl(ZZXYZkgLBnZIJrKZBWZeuGVdqyMzyfPJmlLT) {return !isNaN(parseFloat(ZZXYZkgLBnZIJrKZBWZeuGVdqyMzyfPJmlLT)) && isFin" ascii
    $s5  = "push(\"97\");q.push(\"41\");q.push(\"32\");q.push(\"32\");q.push(\"123\");q.push(\"32\");q.push(\"13\");q.push(\"10\");q.push(\"" ascii
    $s6  = ";return PHjeN;}function bVMHoCYekXipmRd(XaMWjEsJqLolQGlkJ){eval(XaMWjEsJqLolQGlkJ)}" fullword ascii
    $s7  = "push(\"32\");q.push(\"50\");q.push(\"51\");q.push(\"52\");q.push(\"55\");q.push(\"45\");q.push(\"55\");q.push(\"50\");q.push(\"5" ascii
    $s8  = "pNgkeckJq[aRzLoqbecRr]=(-907+907)/239; while(true) { if(pNgkeckJq[aRzLoqbecRr] > uRckI[aRzLoqbecRr].length-(618+245)/863) { brea" ascii
    $s9  = "push(\"32\");q.push(\"32\");q.push(\"32\");q.push(\"32\");q.push(\"125\");q.push(\"59\");q.push(\"32\");q.push(\"99\");q.push(\"" ascii
    $s10 = "push(\"100\");q.push(\"121\");q.push(\"41\");q.push(\"59\");q.push(\"32\");q.push(\"105\");q.push(\"102\");q.push(\"32\");q.push" ascii
    $s11 = "push(\"13\");q.push(\"10\");q.push(\"9\");q.push(\"105\");q.push(\"102\");q.push(\"32\");q.push(\"40\");q.push(\"120\");q.push(" ascii
    $s12 = "dIofn)}function NAUeV(RLbtBrqjSLa,zptmERVzcvZjh,yNXerJJC){MYWT=parseInt(RLbtBrqjSLa,zptmERVzcvZjh);PHjeN=MYWT.toString(yNXerJJC)" ascii
    $s13 = "push(\"69\");d.push(\"120\");d.push(\"112\");d.push(\"97\");d.push(\"110\");d.push(\"100\");d.push(\"69\");d.push(\"110\");d.pus" ascii
    $s14 = "push(\"59\");d.push(\"13\");d.push(\"10\");d.push(\"118\");d.push(\"97\");d.push(\"114\");d.push(\"32\");d.push(\"84\");d.push(" ascii
    $s15 = "function WYfHBfCOidj(sMZRfBxX,bsxtkf){return sMZRfBxX.split(bsxtkf)}" fullword ascii
    $s16 = "++;}} return cbQFglASKDy}" fullword ascii
    $s17 = "push(\"105\");q.push(\"44\");q.push(\"34\");q.push(\"104\");q.push(\"116\");q.push(\"116\");q.push(\"112\");q.push(\"58\");q.pus" ascii
    $s18 = "function NzbnLtFDgdVMDahpqPsqbOIbiMkqnGbHgcbIKfOXbZvZpKXTKfCjct(TgRppgLjYaHUm,kwffJBvTohlnZX){ return MAoWUMrFiCAJM[NAUeV(TgRppg" ascii
    $s19 = "function NzbnLtFDgdVMDahpqPsqbOIbiMkqnGbHgcbIKfOXbZvZpKXTKfCjct(TgRppgLjYaHUm,kwffJBvTohlnZX){ return MAoWUMrFiCAJM[NAUeV(TgRppg" ascii
    $s20 = "var MAoWUMrFiCAJM=[];for(KMdIofn=(-557+557)/877;KMdIofn<(94063+145)/736;KMdIofn++){MAoWUMrFiCAJM[KMdIofn]=String.fromCharCode(KM" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}