rule TTP_XOR_QUAD_CurrentVersionRun_a76a {
  strings:
    $key_a76a = { f4 05 [2] d0 0b [2] fb 27 [2] d5 05 [2] c1 1e [2] ce 04 [2] d0 19 [2] d2 18 [2] c9 1e [2] d5 19 [2] c9 36 }

  condition:
    any of them
}