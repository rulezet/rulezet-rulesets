rule TTP_XOR_QUAD_CurrentVersionRun_e480 {
  strings:
    $key_e480 = { b7 ef [2] 93 e1 [2] b8 cd [2] 96 ef [2] 82 f4 [2] 8d ee [2] 93 f3 [2] 91 f2 [2] 8a f4 [2] 96 f3 [2] 8a dc }

  condition:
    any of them
}