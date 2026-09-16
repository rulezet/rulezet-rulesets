rule TTP_XOR_WriteProcessMemory_700a {
  strings:
    $key_700a = { 27 78 [2] 15 5a [2] 13 6f [2] 3d 6f [2] 02 73 }

  condition:
    any of them
}