rule TTP_XOR_QUAD_CurrentVersionRun_dacc {
  strings:
    $key_dacc = { 89 a3 [2] ad ad [2] 86 81 [2] a8 a3 [2] bc b8 [2] b3 a2 [2] ad bf [2] af be [2] b4 b8 [2] a8 bf [2] b4 90 }

  condition:
    any of them
}