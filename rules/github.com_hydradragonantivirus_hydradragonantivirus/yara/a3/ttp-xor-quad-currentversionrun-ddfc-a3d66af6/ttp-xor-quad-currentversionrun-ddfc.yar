rule TTP_XOR_QUAD_CurrentVersionRun_ddfc {
  strings:
    $key_ddfc = { 8e 93 [2] aa 9d [2] 81 b1 [2] af 93 [2] bb 88 [2] b4 92 [2] aa 8f [2] a8 8e [2] b3 88 [2] af 8f [2] b3 a0 }

  condition:
    any of them
}