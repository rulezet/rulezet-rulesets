rule TTP_XOR_QUAD_CurrentVersionRun_ddec {
  strings:
    $key_ddec = { 8e 83 [2] aa 8d [2] 81 a1 [2] af 83 [2] bb 98 [2] b4 82 [2] aa 9f [2] a8 9e [2] b3 98 [2] af 9f [2] b3 b0 }

  condition:
    any of them
}