rule TTP_XOR_QUAD_CurrentVersionRun_d77e {
  strings:
    $key_d77e = { 84 11 [2] a0 1f [2] 8b 33 [2] a5 11 [2] b1 0a [2] be 10 [2] a0 0d [2] a2 0c [2] b9 0a [2] a5 0d [2] b9 22 }

  condition:
    any of them
}