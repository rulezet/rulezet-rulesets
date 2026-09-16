rule TTP_XOR_QUAD_CurrentVersionRun_eada {
  strings:
    $key_eada = { b9 b5 [2] 9d bb [2] b6 97 [2] 98 b5 [2] 8c ae [2] 83 b4 [2] 9d a9 [2] 9f a8 [2] 84 ae [2] 98 a9 [2] 84 86 }

  condition:
    any of them
}