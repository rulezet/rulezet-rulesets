rule Win_Trojan_Konkoor_1
{
strings:
	$a0 = { 5152565755b430cd213d050074243d06007503e98c003d03307461b402b207cd212bc02bdb8cca8ec28eda5d5f5e5a }


condition:
	$a0
}