rule TTP_XOR_QUAD_CurrentVersionRun_b022 {
  strings:
    $key_b022 = { e3 4d [2] c7 43 [2] ec 6f [2] c2 4d [2] d6 56 [2] d9 4c [2] c7 51 [2] c5 50 [2] de 56 [2] c2 51 [2] de 7e }

  condition:
    any of them
}