rule TTP_XOR_QUAD_CurrentVersionRun_ddde {
  strings:
    $key_ddde = { 8e b1 [2] aa bf [2] 81 93 [2] af b1 [2] bb aa [2] b4 b0 [2] aa ad [2] a8 ac [2] b3 aa [2] af ad [2] b3 82 }

  condition:
    any of them
}