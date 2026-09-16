rule criakl_russian_meta_content
{
strings:
  $h1="<meta content=\"ru\"" nocase
condition:
  all of them
}