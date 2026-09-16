rule TTP_XOR_QUAD_CurrentVersionRun_ae1e {
  strings:
    $key_ae1e = { fd 71 [2] d9 7f [2] f2 53 [2] dc 71 [2] c8 6a [2] c7 70 [2] d9 6d [2] db 6c [2] c0 6a [2] dc 6d [2] c0 42 }

  condition:
    any of them
}