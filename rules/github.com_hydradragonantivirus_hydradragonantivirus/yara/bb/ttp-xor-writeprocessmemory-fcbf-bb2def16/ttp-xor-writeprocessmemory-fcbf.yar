rule TTP_XOR_WriteProcessMemory_fcbf {
  strings:
    $key_fcbf = { ab cd [2] 99 ef [2] 9f da [2] b1 da [2] 8e c6 }

  condition:
    any of them
}