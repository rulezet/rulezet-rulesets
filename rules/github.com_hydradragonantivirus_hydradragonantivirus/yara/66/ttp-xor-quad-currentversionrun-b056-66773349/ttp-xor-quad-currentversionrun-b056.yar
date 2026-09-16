rule TTP_XOR_QUAD_CurrentVersionRun_b056 {
  strings:
    $key_b056 = { e3 39 [2] c7 37 [2] ec 1b [2] c2 39 [2] d6 22 [2] d9 38 [2] c7 25 [2] c5 24 [2] de 22 [2] c2 25 [2] de 0a }

  condition:
    any of them
}