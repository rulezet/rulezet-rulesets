rule TTP_XOR_QUAD_CurrentVersionRun_d84f {
  strings:
    $key_d84f = { 8b 20 [2] af 2e [2] 84 02 [2] aa 20 [2] be 3b [2] b1 21 [2] af 3c [2] ad 3d [2] b6 3b [2] aa 3c [2] b6 13 }

  condition:
    any of them
}