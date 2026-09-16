rule TTP_XOR_QUAD_CurrentVersionRun_a721 {
  strings:
    $key_a721 = { f4 4e [2] d0 40 [2] fb 6c [2] d5 4e [2] c1 55 [2] ce 4f [2] d0 52 [2] d2 53 [2] c9 55 [2] d5 52 [2] c9 7d }

  condition:
    any of them
}