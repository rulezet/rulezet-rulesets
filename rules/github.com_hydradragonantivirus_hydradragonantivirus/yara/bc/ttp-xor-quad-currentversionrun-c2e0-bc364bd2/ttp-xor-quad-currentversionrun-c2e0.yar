rule TTP_XOR_QUAD_CurrentVersionRun_c2e0 {
  strings:
    $key_c2e0 = { 91 8f [2] b5 81 [2] 9e ad [2] b0 8f [2] a4 94 [2] ab 8e [2] b5 93 [2] b7 92 [2] ac 94 [2] b0 93 [2] ac bc }

  condition:
    any of them
}