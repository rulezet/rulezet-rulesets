rule TTP_XOR_WriteProcessMemory_3fbf {
  strings:
    $key_3fbf = { 68 cd [2] 5a ef [2] 5c da [2] 72 da [2] 4d c6 }

  condition:
    any of them
}