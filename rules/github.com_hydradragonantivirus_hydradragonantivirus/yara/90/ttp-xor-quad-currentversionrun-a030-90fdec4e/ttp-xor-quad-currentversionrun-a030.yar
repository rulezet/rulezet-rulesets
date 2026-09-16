rule TTP_XOR_QUAD_CurrentVersionRun_a030 {
  strings:
    $key_a030 = { f3 5f [2] d7 51 [2] fc 7d [2] d2 5f [2] c6 44 [2] c9 5e [2] d7 43 [2] d5 42 [2] ce 44 [2] d2 43 [2] ce 6c }

  condition:
    any of them
}