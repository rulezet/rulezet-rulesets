rule TTP_XOR_QUAD_CurrentVersionRun_ddef {
  strings:
    $key_ddef = { 8e 80 [2] aa 8e [2] 81 a2 [2] af 80 [2] bb 9b [2] b4 81 [2] aa 9c [2] a8 9d [2] b3 9b [2] af 9c [2] b3 b3 }

  condition:
    any of them
}