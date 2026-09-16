rule TTP_XOR_QUAD_CurrentVersionRun_aef2 {
  strings:
    $key_aef2 = { fd 9d [2] d9 93 [2] f2 bf [2] dc 9d [2] c8 86 [2] c7 9c [2] d9 81 [2] db 80 [2] c0 86 [2] dc 81 [2] c0 ae }

  condition:
    any of them
}