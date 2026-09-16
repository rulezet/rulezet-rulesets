rule TTP_XOR_QUAD_CurrentVersionRun_d0fe {
  strings:
    $key_d0fe = { 83 91 [2] a7 9f [2] 8c b3 [2] a2 91 [2] b6 8a [2] b9 90 [2] a7 8d [2] a5 8c [2] be 8a [2] a2 8d [2] be a2 }

  condition:
    any of them
}