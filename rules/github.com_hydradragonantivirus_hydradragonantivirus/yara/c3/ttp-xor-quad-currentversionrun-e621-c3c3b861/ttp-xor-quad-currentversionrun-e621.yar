rule TTP_XOR_QUAD_CurrentVersionRun_e621 {
  strings:
    $key_e621 = { b5 4e [2] 91 40 [2] ba 6c [2] 94 4e [2] 80 55 [2] 8f 4f [2] 91 52 [2] 93 53 [2] 88 55 [2] 94 52 [2] 88 7d }

  condition:
    any of them
}