rule TTP_XOR_WriteProcessMemory_acbf {
  strings:
    $key_acbf = { fb cd [2] c9 ef [2] cf da [2] e1 da [2] de c6 }

  condition:
    any of them
}