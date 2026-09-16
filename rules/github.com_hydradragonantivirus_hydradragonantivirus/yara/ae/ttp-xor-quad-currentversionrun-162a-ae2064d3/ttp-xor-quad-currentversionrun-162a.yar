rule TTP_XOR_QUAD_CurrentVersionRun_162a {
  strings:
    $key_162a = { 45 45 [2] 61 4b [2] 4a 67 [2] 64 45 [2] 70 5e [2] 7f 44 [2] 61 59 [2] 63 58 [2] 78 5e [2] 64 59 [2] 78 76 }

  condition:
    any of them
}