rule TTP_XOR_QUAD_CurrentVersionRun_b014 {
  strings:
    $key_b014 = { e3 7b [2] c7 75 [2] ec 59 [2] c2 7b [2] d6 60 [2] d9 7a [2] c7 67 [2] c5 66 [2] de 60 [2] c2 67 [2] de 48 }

  condition:
    any of them
}