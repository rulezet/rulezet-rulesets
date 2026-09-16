rule TTP_XOR_QUAD_CurrentVersionRun_c103 {
  strings:
    $key_c103 = { 92 6c [2] b6 62 [2] 9d 4e [2] b3 6c [2] a7 77 [2] a8 6d [2] b6 70 [2] b4 71 [2] af 77 [2] b3 70 [2] af 5f }

  condition:
    any of them
}