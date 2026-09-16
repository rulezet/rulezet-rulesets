rule TTP_XOR_QUAD_CurrentVersionRun_33ac {
  strings:
    $key_33ac = { 60 c3 [2] 44 cd [2] 6f e1 [2] 41 c3 [2] 55 d8 [2] 5a c2 [2] 44 df [2] 46 de [2] 5d d8 [2] 41 df [2] 5d f0 }

  condition:
    any of them
}