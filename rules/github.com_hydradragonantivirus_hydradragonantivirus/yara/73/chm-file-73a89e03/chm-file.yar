rule chm_file
{
  strings:
    $magic = { 49 54 53 46 03 00 00 00  60 00 00 00 01 00 00 00 }
  condition:
    $magic
}