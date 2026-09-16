rule TTP_XOR_QUAD_CurrentVersionRun_dcde {
  strings:
    $key_dcde = { 8f b1 [2] ab bf [2] 80 93 [2] ae b1 [2] ba aa [2] b5 b0 [2] ab ad [2] a9 ac [2] b2 aa [2] ae ad [2] b2 82 }

  condition:
    any of them
}