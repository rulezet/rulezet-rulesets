rule TTP_XOR_QUAD_CurrentVersionRun_dd3c {
  strings:
    $key_dd3c = { 8e 53 [2] aa 5d [2] 81 71 [2] af 53 [2] bb 48 [2] b4 52 [2] aa 4f [2] a8 4e [2] b3 48 [2] af 4f [2] b3 60 }

  condition:
    any of them
}