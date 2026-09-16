rule TTP_XOR_QUAD_CurrentVersionRun_c6e3 {
  strings:
    $key_c6e3 = { 95 8c [2] b1 82 [2] 9a ae [2] b4 8c [2] a0 97 [2] af 8d [2] b1 90 [2] b3 91 [2] a8 97 [2] b4 90 [2] a8 bf }

  condition:
    any of them
}